use inc::Module::Install;
name 'Plack-Middleware-Auth-Signed';
all_from 'lib/Plack/Middleware/Auth/Signed.pm';
readme_from "lib/Plack/Middleware/Auth/Signed.pm";

requires 'Plack';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t t/*/*/*/*/*.t';
author_tests 'xt';
auto_set_repository;
build_requires 'Test::More', 0.88;
auto_include;
WriteAll;

