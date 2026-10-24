import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenMantisSafe {

    private boolean checkGoldenMantisAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenMantisAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_MANTIS_ACCOUNT_ID");
        boolean authorized = checkGoldenMantisAccess(data);
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        try {
            PreparedStatement goldenMantisDelete = goldenMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenMantisDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenMantisDelete.executeUpdate();
            }
        } finally {
            goldenMantisConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
