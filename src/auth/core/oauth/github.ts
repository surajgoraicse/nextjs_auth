import { env } from "@/data/env/server";
import { z } from "zod";
import { OAuthClient } from "./base";

export function createGithubOAuthClient() {
	return new OAuthClient({
		provider: "github",
		client_id: env.GITHUB_CLIENT_ID,
		client_secret: env.GITHUB_CLIENT_SECRET,
		scopes: ["user:email", "read:user"],
		urls: {
			auth: "https://github.com/login/oauth/authorize",
			token: "https://github.com/login/oauth/access_token",
			user: "https://api.github.com/user",
		},
		userInfo: {
			schema: z.object({
				id: z.number(),
				name: z.string().nullable(),
				login: z.string(),
				email: z.string().email().nullable(),
			}),
			getUserDetails: async (user) => ({
				id: user.id.toString(),
				name: user.name ?? user.login,
				email: user.email ?? "",
			}),
		},
	});
}
