<?php
// SAFE: Eloquent's where() binds parameters automatically. Trap: passing the
// request value into where() looks like raw SQL, but the query builder binds it,
// so no injection is possible.
function search() {
    $term = $_GET['term'];
    return App\Models\Product::where('name', 'like', $term)->get();
}
