"use server";

import { db } from "@/drizzle/db";
import { OAuthProvider, UserTable } from "@/drizzle/schema";
import { eq } from "drizzle-orm";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";
import { getOAuthClient } from "../core/oauth/base";
import { comparePasswords } from "../core/passwordHasher";
import { createUserSession, removeUserFromSession } from "../core/session";
import { signInSchema, signUpSchema } from "./schemas";

export async function signIn(unsafeData: z.infer<typeof signInSchema>) {
	const { success, data } = signInSchema.safeParse(unsafeData);

	if (!success) return "Unable to log you in";

	const user = await db.query.UserTable.findFirst({
		columns: {
			password: true,
			salt: true,
			id: true,
			email: true,
			role: true,
		},
		where: eq(UserTable.email, data.email),
	});

	if (user == null || user.password == null || user.salt == null) {
		return "Unable to log you in";
	}

	const isCorrectPassword = await comparePasswords({
		hashedPassword: user.password,
		password: data.password,
		salt: user.salt,
	});

	if (!isCorrectPassword) return "Unable to log you in";

	await createUserSession(user, await cookies());

	redirect("/");
}

export async function signUp(unsafeData: z.infer<typeof signUpSchema>) {
	const { success, data } = signUpSchema.safeParse(unsafeData);

	if (!success) return "Unable to create account";

	// check for existing user
	const existingUser = await db.query.UserTable.findFirst({
		where: eq(UserTable.email, data.email),
	});
	if (existingUser != null) return "Account already exists for this email";

	redirect("/");
}

export async function logOut() {
	await removeUserFromSession(await cookies());
	redirect("/");
}

export async function oAuthSignIn(provider: OAuthProvider) {
	const oAuthClient = getOAuthClient(provider);
	redirect(oAuthClient.createAuthUrl(await cookies()));
}
