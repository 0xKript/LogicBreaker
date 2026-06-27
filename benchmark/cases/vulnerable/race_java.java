public class Bank {
    private double balance = 1000.0;
    // VULN: race condition
    public boolean transfer(double amount) {
        if (balance >= amount) {
            Thread.sleep(10);
            balance -= amount;
            return true;
        }
        return false;
    }
}
