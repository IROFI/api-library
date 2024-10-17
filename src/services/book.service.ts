import { ForeignKeyConstraintError } from "sequelize";
import { BookOutputDTO } from "../dto/book.dto";
import { BookCollectionOutputDTO } from "../dto/bookCollection.dto";
import { notFound } from "../error/NotFoundError";
import { BookMapper } from "../mapper/book.mapper";
import { BookCollectionMapper } from "../mapper/bookCollection.mapper";
import { Author } from "../models/author.model";
import { Book } from "../models/book.model";
import { BookCollection } from "../models/bookCollection.model";

export class BookService {
  readonly includeAuthor = {
    include: [
      {
        model: Author,
        as: "author",
      },
    ],
  };
  public async getAllBooks(): Promise<BookOutputDTO[]> {
    let books = await Book.findAll(this.includeAuthor);

    return BookMapper.toOutputDtoList(books);
  }

  public async getBookById(id: number): Promise<BookOutputDTO> {
    let book = await Book.findByPk(id, this.includeAuthor);

    if (book) {
      return BookMapper.toOutputDto(book);
    } else {
      notFound("Book");
    }
  }

  public async createBook(
    title: string,
    publishYear: number,
    authorId: number,
    isbn: string
  ): Promise<BookOutputDTO> {
    try {
      let book = await Book.create({
        title: title,
        publish_year: publishYear,
        isbn: isbn,
        author_id: authorId,
      });

      return BookMapper.toOutputDto(book);
    } catch (err) {
      if (err instanceof ForeignKeyConstraintError) {
        throw notFound("Author");
      }
      throw err;
    }
  }

  public async updateBook(
    id: number,
    title?: string,
    publishYear?: number,
    authorId?: number,
    isbn?: string
  ): Promise<BookOutputDTO> {
    const book = await Book.findByPk(id);
    if (book) {
      if (title !== undefined) book.title = title;
      if (publishYear != undefined) book.publish_year = publishYear;
      if (authorId !== undefined) book.author_id = authorId;
      if (isbn !== undefined) book.isbn = isbn;
      try {
        await book.save();
      } catch (err) {
        if (err instanceof ForeignKeyConstraintError) {
          throw notFound("Author");
        }
        throw err;
      }
      return BookMapper.toOutputDto(book);
    } else {
      notFound("Book");
    }
  }

  public async deleteBook(id: number): Promise<void> {
    const book = await Book.findByPk(id, {
      include: [
        {
          model: BookCollection,
          as: "collections",
        },
      ],
    });
    if (book) {
      if (book.collections.length > 0) {
        const error = new Error(
          "Deletion of book " +
            id +
            " isn't possible due to presence of his.er books in library"
        );
        (error as any).status = 412;
        throw error;
      } else {
        book.destroy();
      }
    } else {
      notFound("Book");
    }
  }

  public async getBookCollectionsByBookId(
    id: number
  ): Promise<BookCollectionOutputDTO[]> {
    return BookCollectionMapper.toOutputDtoList(
      await BookCollection.findAll({
        where: {
          book_id: id,
        },
      })
    );
  }

  public async checkAuthorExists(authorId: number): Promise<boolean> {
    const author = await Author.findByPk(authorId);
    return author !== null;
  }
}

export const bookService = new BookService();
