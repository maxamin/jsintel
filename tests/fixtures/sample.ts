interface User {
  id: number;
  name: string;
}

function greet(user: User): string {
  return `Hello, ${user.name}`;
}

const admin: User = { id: 1, name: "Admin" };
greet(admin);
