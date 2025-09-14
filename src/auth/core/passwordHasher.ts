import crypto from "crypto";

export function hashPassword(password: string, salt: string): Promise<string> {
	return new Promise((resolve, reject) => {
		crypto.scrypt(password.normalize(), salt, 64, (error, hash) => {
			if (error) reject(error);

			resolve(hash.toString("hex").normalize());
		});
	});
}

export async function comparePasswords({
	password,
	salt,
	hashedPassword,
}: {
	password: string;
	salt: string;
	hashedPassword: string;
}) {
	const hashUserPassword = await hashPassword(password, salt);

	// return hashUserPassword === hashedPassword // vernareble from timing based attack

	return crypto.timingSafeEqual(
		Buffer.from(hashUserPassword, "hex"),
		Buffer.from(hashedPassword, "hex")
	);
}
export function generateSalt() {
	return crypto.randomBytes(16).toString("hex").normalize();
}
