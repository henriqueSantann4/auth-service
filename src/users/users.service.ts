import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, AuthProvider } from './user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async createLocalUser(data: {
    email: string;
    password: string;
    name: string;
  }): Promise<User> {
    const user = this.usersRepository.create({
      ...data,
      provider: AuthProvider.LOCAL,
    });

    return this.usersRepository.save(user);
  }

  async markEmailAsVerified(userId: string): Promise<void> {
    await this.usersRepository.update(userId, { isEmailVerified: true });
  }
}