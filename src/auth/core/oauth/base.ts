import { env } from "@/data/env/server";
import { OAuthProvider } from "@/drizzle/schema";
import crypto from "crypto";
import z from "zod";
import { Cookies } from "../session";
import { createDiscordOAuthClient } from "./discord";
import { createGithubOAuthClient } from "./github";

const COOKIE_EXPIRATION_SECONDS = 60 * 10;
const STATE_COOKIE_KEY = "oauth_state";
const CODE_VERIFIER_COOKIE_KEY = "oauth_code_verifier";

export class OAuthClient<T> {
	private readonly provider: OAuthProvider;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private readonly scopes: string[];
	private readonly urls: {
		auth: string;
		token: string;
		user: string;
	};

	private readonly userInfo: {
		schema: z.Schema<T>;
		getUserDetails: (
			data: T,
			accessToken: string
		) => Promise<{ id: string; email: string; name: string }>;
	};
	private readonly tokenSchema = z.object({
		access_token: z.string(),
		token_type: z.string(),
	});

	constructor({
		provider,
		client_id,
		client_secret,
		scopes,
		urls,
		userInfo,
	}: {
		provider: OAuthProvider;
		client_id: string;
		client_secret: string;
		scopes: string[];
		urls: {
			auth: string;
			token: string;
			user: string;
		};
		userInfo: {
			schema: z.Schema<T>;
			getUserDetails: (
				data: T,
				accessToken: string
			) => Promise<{ id: string; email: string; name: string }>;
		};
	}) {
		this.provider = provider;
		this.clientId = client_id;
		this.clientSecret = client_secret;
		this.scopes = scopes;
		this.urls = urls;
		this.userInfo = userInfo;
	}

	private get redirectUrl() {
		// Ensure trailing slash in OAUTH_REDIRECT_URL_BASE
		return new URL(
			`/api/oauth/${this.provider}`,
			env.OAUTH_REDIRECT_URL_BASE
		);
	}

	/**
	 * Step 1: Generate Authorization URL
	 */
	createAuthUrl(cookies: Pick<Cookies, "set">) {
		const state = createState(cookies);
		const codeVerifier = createCodeVerifier(cookies);
		const url = new URL(this.urls.auth);
		url.searchParams.set("client_id", this.clientId);
		url.searchParams.set("redirect_uri", this.redirectUrl.toString());
		url.searchParams.set("scope", this.scopes.join(" "));
		url.searchParams.set("response_type", "code");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge_method", "S256");
		url.searchParams.set(
			"code_challenge",
			crypto.createHash("sha256").update(codeVerifier).digest("base64url")
		);

		return url.toString();
	}

	/**
	 * Step 2: Exchange code for access token
	 */
	private async fetchToken(code: string, codeVerifier: string) {
		const response = await fetch(this.urls.token, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json",
			},
			body: new URLSearchParams({
				code,
				redirect_uri: this.redirectUrl.toString(),
				client_id: this.clientId,
				client_secret: this.clientSecret,
				code_verifier: codeVerifier,
			}),
		});

		const rawData = await response.json();
		console.log(`${this.provider} Token Response:`, rawData);

		const parsed = this.tokenSchema.safeParse(rawData);
		if (!parsed.success) {
			throw new InvalidTokenError(parsed.error);
		}

		return parsed.data;
	}

	/**
	 * Step 3: Use access token to fetch user info
	 */
	async fetchUser(
		code: string,
		state: string,
		cookies: Pick<Cookies, "get">
	) {
		const isValidState = await validateState(state, cookies);
		if (!isValidState) {
			throw new InvalidStateError();
		}

		const { access_token, token_type } = await this.fetchToken(
			code,
			getCodeVerifier(cookies)
		);

		const userResponse = await fetch(this.urls.user, {
			headers: {
				Authorization: `${token_type} ${access_token}`,
				Accept: "application/vnd.github+json",
			},
		});
		const rawUser = await userResponse.json();
		console.log(`${this.provider} User Response:`, rawUser);

		const parsedUser = this.userInfo.schema.safeParse(rawData);

		if (!parsedUser.success) {
			throw new InvalidUserError(parsedUser.error);
		}

		return this.userInfo.getUserDetails(parsedUser.data, accessToken);
	}
}

// Error classes
export class InvalidTokenError extends Error {
	constructor(zodError: z.ZodError) {
		super("Invalid Token");
		this.cause = zodError;
	}
}

export class InvalidUserError extends Error {
	constructor(zodError: z.ZodError) {
		super("Invalid User");
		this.cause = zodError;
	}
}
export class InvalidStateError extends Error {
	constructor() {
		super("Invalid state");
	}
}

function createState(cookies: Pick<Cookies, "set">) {
	const state = crypto.randomBytes(64).toString("hex").normalize();
	cookies.set(STATE_COOKIE_KEY, state, {
		secure: true,
		httpOnly: true,
		sameSite: "lax",
		expires: Date.now() + COOKIE_EXPIRATION_SECONDS * 1000,
	});
	return state;
}

function validateState(state: string, cookies: Pick<Cookies, "get">) {
	const cookieState = cookies.get(STATE_COOKIE_KEY)?.value;
	return cookieState === state;
}

function createCodeVerifier(cookies: Pick<Cookies, "set">) {
	const codeVerifier = crypto.randomBytes(64).toString("hex").normalize();
	cookies.set(CODE_VERIFIER_COOKIE_KEY, codeVerifier, {
		secure: true,
		httpOnly: true,
		sameSite: "lax",
		expires: Date.now() + COOKIE_EXPIRATION_SECONDS * 1000,
	});
	return codeVerifier;
}

function getCodeVerifier(cookies: Pick<Cookies, "get">) {
	const codeVerifier = cookies.get(CODE_VERIFIER_COOKIE_KEY)?.value;
	if (codeVerifier == null) throw new InvalidCodeVerifierError();
	return codeVerifier;
}

export class InvalidCodeVerifierError extends Error {
	constructor() {
		super("Invalid code verifier");
	}
}

export function getOAuthClient(provider: OAuthProvider) {
	switch (provider) {
		case "discord":
			return createDiscordOAuthClient();
		case "github":
			return createGithubOAuthClient();
		default:
			throw new Error(`Unknown OAuth provider: ${provider}`);
	}
}
