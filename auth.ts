import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { authConfig } from './auth.config';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

// Function to fetch user by email from the database
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        // Parse and validate the credentials using Zod
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        // If validation fails, return null
        if (!parsedCredentials.success) {
          return null;
        }

        // Destructure the credentials
        const { email, password } = parsedCredentials.data;

        // Fetch the user from the database
        const user = await getUser(email);
        if (!user) {
          console.log('User not found');
          return null; // Return null if the user is not found
        }

        // Compare the hashed password using bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          console.log('Invalid credentials');
          return null; // Return null if the password is incorrect
        }

        // Return the user object if the password is correct
        return user;
      },
    }),
  ],
});

// Example of a user authentication function
async function authenticateUser(email: string, password: string) {
  const user = { id: '1', email: 'user@example.com' }; // Example user object

  // If credentials match, return the user; otherwise, return null
  if (email === user.email && password === 'validpassword') {
    return user; // Return the user object if authentication succeeds
  }

  return null; // Return null if authentication fails
}
