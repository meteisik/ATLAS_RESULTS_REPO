import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenSundialSafe {

    private boolean checkGoldenSundialAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenSundialAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_ACCOUNT_ID");
        boolean authorized = checkGoldenSundialAccess(data);
        Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
        try {
            PreparedStatement goldenSundialDelete = goldenSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenSundialDelete.executeUpdate();
            }
        } finally {
            goldenSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
