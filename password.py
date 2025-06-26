from werkzeug.security import generate_password_hash, check_password_hash

password = 'zubenko1'
#faurva37
#zubpetr

p = generate_password_hash(password)
print(generate_password_hash(password))

print(check_password_hash(p, password))


