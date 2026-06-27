// SAFE: Go database/sql with a $1 placeholder. Trap: the id from the query string
// is passed to Query(), which looks like injection, but it is a bound parameter.
package main
import ("database/sql"; "net/http")
func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    rows, _ := db.Query("SELECT name FROM users WHERE id = $1", id)
    defer rows.Close()
}
