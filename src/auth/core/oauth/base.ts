import { env } from "@/data/env/server";
import crypto from "crypto";
import z from "zod";
import { Cookies } from "../session";

const COOKIE_EXPIRATION_SECONDS = 60 * 10;
const STATE_COOKIE_KEY = "oauth_state";
const CODE_VERIFIER_COOKIE_KEY = "oauth_code_verifier";

export class OAuthClient<T> {



	private get redirectUrl() {
		// Ensure trailing slash in OAUTH_REDIRECT_URL_BASE
		return new URL("/api/oauth/github", env.OAUTH_REDIRECT_URL_BASE);
	}

	// GitHub token response schema
	private readonly tokenSchema = z.object({
		access_token: z.string(),
		token_type: z.string(),
		scope: z.string().optional(),
	});

	// GitHub user response schema
	private readonly userSchema = z.object({
		id: z.number(), // GitHub returns numeric id
		login: z.string(),
		name: z.string().nullable(),
		email: z.string().email().nullable(),
	});


	/**
	 * Step 1: Generate GitHub Authorization URL
	 */
	createAuthUrl(cookies: Pick<Cookies, "set">) {
		const state = createState(cookies);
		const codeVerifier = createCodeVerifier(cookies);
		const url = new URL("https://github.com/login/oauth/authorize");
		url.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
		url.searchParams.set("redirect_uri", this.redirectUrl.toString());
		url.searchParams.set("scope", "read:user user:email");
		url.searchParams.set("response_type", "code");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge_method", "S256");
		url.searchParams.set(
			"code_challenge",
			crypto.hash("sha256", codeVerifier, "base64url")
		);

		return url.toString();
	}

	/**
	 * Step 2: Exchange code for access token
	 */
	private async fetchToken(code: string, codeVerifier: string) {
		const response = await fetch(
			"https://github.com/login/oauth/access_token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Accept: "application/json",
				},
				body: new URLSearchParams({
					code,
					redirect_uri: this.redirectUrl.toString(),
					client_id: env.GITHUB_CLIENT_ID,
					client_secret: env.GITHUB_CLIENT_SECRET,
					code_verifier: codeVerifier,
				}),
			}
		);

		const rawData = await response.json();
		console.log("GitHub Token Response:", rawData);

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

		// Step 1: fetch base user profile
		const userResponse = await fetch("https://api.github.com/user", {
			headers: {
				Authorization: `${token_type} ${access_token}`,
				Accept: "application/vnd.github+json",
			},
		});
		const rawUser = await userResponse.json();
		console.log("GitHub User Response:", rawUser);

		const parsedUser = this.userSchema.safeParse(rawUser);
		if (!parsedUser.success) {
			throw new InvalidUserError(parsedUser.error);
		}

		// Step 2: fetch emails
		const emailResponse = await fetch(
			"https://api.github.com/user/emails",
			{
				headers: {
					Authorization: `${token_type} ${access_token}`,
					Accept: "application/vnd.github+json",
				},
			}
		);
		const emails: { email: string; primary: boolean; verified: boolean }[] =
			await emailResponse.json();

		const primaryEmail =
			emails.find((e) => e.primary && e.verified)?.email ??
			emails.find((e) => e.verified)?.email ??
			null;

		return {
			id: parsedUser.data.id.toString(),
			email: primaryEmail,
			name: parsedUser.data.name ?? parsedUser.data.login,
		};
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
