import { Buffer } from "buffer"; // Pour décoder Base64
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { notFound } from "../error/NotFoundError";
import { User } from "../models/user.model"; // Modèle Sequelize

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key"; // Clé secrète pour signer le token

export class AuthenticationService {
  public async authenticate(
    username: string,
    password: string
  ): Promise<string> {
    // Recherche l'utilisateur dans la base de données
    const user = await User.findOne({ where: { username } });

    if (!user) {
      throw notFound("User");
    }

    // Décoder le mot de passe stocké en base de données
    const decodedPassword = Buffer.from(user.password, "base64").toString(
      "utf-8"
    );

    // Vérifie si le mot de passe est correct
    if (password === decodedPassword) {
      // Si l'utilisateur est authentifié, on génère un JWT
      const permissions = this.getPermissions(username);
      const token = jwt.sign(
        { username: user.username, permissions },
        JWT_SECRET,
        {
          expiresIn: "1h",
        }
      );
      return token;
    } else {
      let error = new Error("Mot de passe incorrect");
      (error as any).status = 403;
      throw error;
    }
  }

  private getPermissions(username: string): { [key: string]: string[] } {
    const permissions: { [key: string]: string[] } = {
      author: [],
      book: [],
      bookCollection: [],
      user: [],
    };

    switch (username) {
      case "admin":
        permissions.author = ["read", "write", "delete"];
        permissions.book = ["read", "write", "delete"];
        permissions.bookCollection = ["read", "write", "delete"];
        permissions.user = ["read", "write", "delete"];
        break;
      case "gerant":
        permissions.author = ["read", "write"];
        permissions.book = ["read", "write"];
        permissions.bookCollection = ["read", "write", "delete"];
        permissions.user = ["read"];
        break;
      case "utilisateur":
        permissions.author = ["read"];
        permissions.book = ["read", "write"];
        permissions.bookCollection = ["read"];
        permissions.user = ["read"];
        break;
      default:
        // Permissions par défaut (aucune)
        break;
    }

    return permissions;
  }
}

export const authService = new AuthenticationService();
