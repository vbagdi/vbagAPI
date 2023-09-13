import { Collection, UpdateFilter } from "mongodb";
import { UserSchema } from "./user-schemas.js";
import DatabaseHelper from "../../database.js";
import { UserFormat } from "./user-formats.js";
import crypto from "crypto";


/**
 * Get information from user database about a user.
 * @param userId
 * @returns Promise, if successful then data about the user. If failed, contains error.
 */
export async function getUser(userId: string): Promise<UserSchema> {
	const collection: Collection = await DatabaseHelper.getCollection("user", "info");
	console.log("|%s|", userId);
	try {
		const user: UserSchema | null = await collection.findOne({ id: userId }) as UserSchema | null;
		if (user) {
			return user;
		}
		return Promise.reject("UserNotFound");
	} catch (error) {
		return Promise.reject("InternalError");
	}
}


/**
 * Update an EXISTING user's data, given new data. User must exist in this database to be updated.
 * @param userData New information about user to add
 * @returns Promise, containing nothing if successful but error if rejected.
 */
export async function updateUser(userData: UserFormat): Promise<void> {
	const collection: Collection = await DatabaseHelper.getCollection("user", "info");

	try {
		// Create the query to run the update, then perform the update operation
		const updateFilter: UpdateFilter<UserSchema> = {
			$set: {
				id: userData.id,
				email: userData.email,
				firstname: userData.firstname,
				lastname: userData.lastname,
			} };
		await collection.updateOne({ id: userData.id }, updateFilter, { upsert: true });
	} catch (error) {
		console.error(error);
		return Promise.reject("InternalError");
	}

	return Promise.resolve();
}

/**
 * Function to encode user and data into a token.
 * @param user User identifier.
 * @param data Data to be encoded.
 * @param secretKey Secret key for encoding.
 * @returns Encoded token and context (optional).
 */
export function encodeToken(user: string, data: JSON, secretKey: string): { token: string, context?: object } {
	const payload: { user: string; data: JSON } = { user, data };
  
	const encodedPayload: string = Buffer.from(JSON.stringify(payload)).toString("base64");
	const signature: string = crypto.createHmac("sha256", secretKey).update(encodedPayload).digest("base64");
  
	const token: string = `${encodedPayload}.${signature}`;
  
	return { token };
}
  


/**
 * Function to decode an encoded token.
 * @param token Encoded token to decode.
 * @param secretKey Secret key for decoding.
 * @returns Decoded user and data with context (optional).
 */
export function decodeToken(token: string, secretKey: string): { user: string, data: JSON, context?: object } {
	const [ encodedPayload, signature ] = token.split(".");
	
	if (!encodedPayload || !signature) {
		throw new Error("Invalid token format");
	}
  
	const expectedSignature: string = crypto.createHmac("sha256", secretKey).update(encodedPayload).digest("base64");
  
	if (signature !== expectedSignature) {
		throw new Error("Invalid token");
	}
	interface Payload {
		user: string;
		data: JSON;
		context?: object;
	}
	const payload: Payload = JSON.parse(Buffer.from(encodedPayload, "base64").toString()) as Payload;
  
	return payload;
}
  

  
