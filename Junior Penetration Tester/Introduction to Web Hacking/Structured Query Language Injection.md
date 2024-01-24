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

### What are Tables?
* A table is made up of columns and rows.
* A useful way to imagine a table is like a grid with the columns going across the top from left to right containing the name of the cell and the rows going from top to bottom with each one having the actual data.

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
* Rows (or records) are what contains the individual lines of data.
* A new row/record is created when data is added to the table.
* A row/record is removed when data is deleted.

### Relational Vs Non-Relational Databases
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

## What is SQL?
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
* An online blog where each blog entry has a unique `id` number.
* The blog entries may be either set to public or private depending on whether they're ready for public release.
* The URL for each blog entry looks like `https://website.thm/blog?id=1`
* Rhe blog entry being selected comes from the `id` parameter in the query string.
* The web application needs to retrieve the article from the database and may use an SQL statement that looks like the following:
```
SELECT * from blog where id=1 and private=0 LIMIT 1;
```
* The SQL statement is looking in the `blog` table for an article with the `id` number of `1` and the `private` column set to `0`, which means it's able to be viewed by the public and limits the results to only one match.
* The `id` parameter from the query string is used directly in the SQL query.
* Article id 2 is still locked as private, so it cannot be viewed on the website.
* Instead, call the URL: `https://website.thm/blog?id=2;--`
* This would produce the SQL statement:
```
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```
* The semicolon in the URL signifies the end of the SQL statement, and the two dashes cause everything afterwards to be treated as a comment.
* Doing this runs the query:
```
SELECT * from blog where id=2;--
```
* Which will return the article with an `id` of 2 whether it is set to public or not.
* This was an example of an in-band SQL Injection vulnerability.

## In-Band SQLi
* In-Band SQL Injection is the easiest type to detect and exploit; In-Band just refers to the same method of communication being used to exploit the vulnerability and also receive the results, for example, discovering an
* SQL Injection vulnerability on a website page and then being able to extract data from the database to the same page.
### Error-Based SQL Injection
* This type of SQL Injection is the most useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browser screen.
* This can often be used to enumerate a whole database. 
### Union-Based SQL Injection
* This type of Injection utilises the SQL UNION operator alongside a SELECT statement to return additional results to the page.
* This method is the most common way of extracting large amounts of data via an SQL Injection vulnerability.
### Practical
* The key to discovering error-based SQL Injection is to break the code's SQL query by trying certain characters until an error message is produced; these are most commonly single apostrophes ( ' ) or a quotation mark ( " ).
* Try typing an apostrophe ( ' ) after the id=1 and press enter.
* And you'll see this returns an SQL error informing you of an error in your syntax.
* The fact that you've received this error message confirms the existence of an SQL Injection vulnerability.
* We can now exploit this vulnerability and use the error messages to learn more about the database structure.
* The first thing we need to do is return data to the browser without displaying an error message.
* Firstly we'll try the UNION operator so we can receive an extra result of our choosing. Try setting the mock browsers id parameter to:
```
1 UNION SELECT 1
```
* This statement should produce an error message informing you that the UNION SELECT statement has a different number of columns than the original SELECT query.
* So let's try again but add another column:
```
1 UNION SELECT 1,2
```
* Same error again, so let's repeat by adding another column:
```
1 UNION SELECT 1,2,3
```
* Success, the error message has gone, and the article is being displayed, but now we want to display our data instead of the article.
* The article is being displayed because it takes the first returned result somewhere in the web site's code and shows that.
* To get around that, we need the first query to produce no results.
* This can simply be done by changing the article id from 1 to 0.
```
0 UNION SELECT 1,2,3
```
* You'll now see the article is just made up of the result from the UNION select returning the column values 1, 2, and 3.
* We can start using these returned values to retrieve more useful information.
* First, we'll get the database name that we have access to:
```
0 UNION SELECT 1,2,database()
```
* You'll now see where the number 3 was previously displayed; it now shows the name of the database, which is sqli_one.
* Our next query will gather a list of tables that are in this database.
```
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
```
* There are a couple of new things to learn in this query.
* Firstly, the method group_concat() gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas.
* The next thing is the information_schema database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to.
* In this particular query, we're interested in listing all the tables in the sqli_one database, which is article and staff_users.
* As the first level aims to discover Martin's password, the staff_users table is what is of interest to us.
* We can utilise the information_schema database again to find the structure of this table using the below query.
```
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
```
* This is similar to the previous SQL query.
* However, the information we want to retrieve has changed from table_name to column_name, the table we are querying in the information_schema database has changed from tables to columns, and we're searching for any rows where the table_name column has a value of staff_users.
* The query results provide three columns for the staff_users table: id, password, and username.
* We can use the username and password columns for our following query to retrieve the user's information.
```
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
```
* Again we use the group_concat method to return all of the rows into one string and to make it easier to read.
* We've also added ,':', to split the username and password from each other.
* Instead of being separated by a comma, we've chosen the HTML <br> tag that forces each result to be on a separate line to make for easier reading.

## Blind SQLi - Authentication Bypass
* Unlike In-Band SQL injection, where we can see the results of our attack directly on the screen, blind SQLi is when we get little to no feedback to confirm whether our injected queries were, in fact, successful or not, this is because the error messages have been disabled, but the injection still works regardless.
* It might surprise you that all we need is that little bit of feedback to successfully enumerate a whole database.
### Authentication Bypass
* One of the most straightforward Blind SQL Injection techniques is when bypassing authentication methods such as login forms.
* In this instance, we aren't that interested in retrieving data from the database; We just want to get past the login.
* Login forms that are connected to a database of users are often developed in such a way that the web application isn't interested in the content of the username and password but more whether the two make a matching pair in the users table.
* In basic terms, the web application is asking the database "do you have a user with the username bob and the password bob123?", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not.
* Taking the above information into account, it's unnecessary to enumerate a valid username/password pair.
* We just need to create a database query that replies with a yes/true.
#### Practical:
We can see in the box labelled "SQL Query" that the query to the database is the following:
```
select * from users where username='%username%' and password='%password%' LIMIT 1;
```
* N.B The %username% and %password% values are taken from the login form fields, the initial values in the SQL Query box will be blank as these fields are currently empty.
* To make this into a query that always returns as true, we can enter the following into the password field:
```
' OR 1=1;--
```
* Which turns the SQL query into the following:
```
select * from users where username='' and password='' OR 1=1;
```
* Because 1=1 is a true statement and we've used an OR operator, this will always cause the query to return as true, which satisfies the web applications logic that the database found a valid username/password combination and that access should be allowed.
  
## Blind SQLi - Boolean Based
* Boolean based SQL Injection refers to the response we receive back from our injection attempts which could be a true/false, yes/no, on/off, 1/0 or any response which can only ever have two outcomes.
* That outcome confirms to us that our SQL Injection payload was either successful or not.
* On the first inspection, you may feel like this limited response can't provide much information.
* Still, in fact, with just these two responses, it's possible to enumerate a whole database structure and contents.
### Practical
* You're presented with a mock browser with the following URL: https://website.thm/checkuser?username=admin
* The browser body contains the contents of {"taken":true}.
* This API endpoint replicates a common feature found on many signup forms, which checks whether a username has already been registered to prompt the user to choose a different username.
* Because the taken value is set to true, we can assume the username admin is already registered.
* In fact, we can confirm this by changing the username in the mock browser's address bar from admin to admin123, and upon pressing enter, you'll see the value taken has now changed to false.
* The SQL query that is processed looks like the following:
```
select * from users where username = '%username%' LIMIT 1;
```
* As the only input we have control over is the username in the query string, we'll have to use this to perform our SQL Injection.
* Keeping the username as admin123, we can start appending to this to try and make the database confirm true things, which will change the state of the taken field from false to true.
* Our first task is to establish the number of columns in the users table, which we can achieve by using the UNION statement.
* Change the username value to the following:
```
admin123' UNION SELECT 1;-- 
```
* As the web application has responded with the value taken as false, we can confirm this is the incorrect value of columns.
* Keep on adding more columns until we have a taken value of true.
* You can confirm that the answer is three columns by setting the username to the below value:
```
admin123' UNION SELECT 1,2,3;-- 
```
* Now that our number of columns has been established, we can work on the enumeration of the database.
* Our first task is discovering the database name.
* We can do this by using the built-in database() method and then using the like operator to try and find results that will return a true status.
* Try the below username value and see what happens:
```
admin123' UNION SELECT 1,2,3 where database() like '%';--
```
* We get a true response because, in the like operator, we just have the value of %, which will match anything as it's the wildcard value.
* If we change the wildcard operator to a%, you'll see the response goes back to false, which confirms that the database name does not begin with the letter a.
* We can cycle through all the letters, numbers and characters such as - and _ until we discover a match.
* If you send the below as the username value, you'll receive a true response that confirms the database name begins with the letter s.
```
admin123' UNION SELECT 1,2,3 where database() like 's%';--
```
* Now you move onto the next character of the database name until you find another true response, for example, 'sa%', 'sb%', 'sc%' etc.
* Keep on with this process until you discover all the characters of the database name, which is sqli_three.
* We've established the database name, which we can now use to enumerate table names using a similar method by utilising the information_schema database.
* Try setting the username to the following value:
```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```
* This query looks for results in the information_schema database in the tables table where the database name matches sqli_three, and the table name begins with the letter a.
* As the above query results in a false response, we can confirm that there are no tables in the sqli_three database that begin with the letter a.
* Like previously, you'll need to cycle through letters, numbers and characters until you find a positive match.
* You'll finally end up discovering a table in the sqli_three database named users, which you can be confirmed by running the following username payload:
```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--
```
* Lastly, we now need to enumerate the column names in the users table so we can properly search it for login credentials.
* Again using the information_schema database and the information we've already gained, we can start querying it for column names.
* Using the payload below, we search the columns table where the database is equal to sqli_three, the table name is users, and the column name begins with the letter a.
```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
```
* Again you'll need to cycle through letters, numbers and characters until you find a match.
* As you're looking for multiple results, you'll have to add this to your payload each time you find a new column name, so you don't keep discovering the same one.
* For example, once you've found the column named id, you'll append that to your original payload (as seen below).
```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';
```
* Repeating this process three times will enable you to discover the columns id, username and password.
* Which now you can use to query the users table for login credentials.
* First, you'll need to discover a valid username which you can use the payload below:
```
admin123' UNION SELECT 1,2,3 from users where username like 'a%
```
* Which, once you've cycled through all the characters, you will confirm the existence of the username admin.
* Now you've got the username.
* You can concentrate on discovering the password.
* The payload below shows you how to find the password:
```
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```
* Cycling through all the characters, you'll discover the password is 3845.

## Blind SQLi - Time Based
* Very similar to Boolean based as same requests are sent.
* No visual indicator of queries being wrong or right.
* Indicator of a correct query is based on the time the query takes to complete.
* Time delay is introduced by using built-in methods such as `SLEEP(x)` alongside the `UNION` statement.
* `SLEEP()` method will only ever get executed upon a successful `UNION SELECT` statement.
* Use the following querywhen trying to establish the number of columns in a table:
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

## Out-of-Band SQLi
* Not as common as it either depends on specific features being enabled on the database server or the web application's business logic, which makes some kind of external network call based on the results from an SQL query.
* Classified by having two different communication channels, one to launch the attack and the other to gather the results. 
  * For example, the attack channel could be a web request, and the data gathering channel could be monitoring HTTP/DNS requests made to a service you control.
### Out-of-Band SQLi Example
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
