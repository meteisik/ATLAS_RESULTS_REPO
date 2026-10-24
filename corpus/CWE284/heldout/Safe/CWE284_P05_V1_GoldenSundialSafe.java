import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_GoldenSundialSafe {

    private String goldenSundialAccountId;

    private boolean goldenSundialAuthorized;

    private void applyGoldenSundialDeletion() throws SQLException {
        String data = goldenSundialAccountId;
        boolean authorized = goldenSundialAuthorized;
        Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
        try {
            PreparedStatement goldenSundialDelete = goldenSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSundialDelete.setString(1, data);
            if (authorized) {
                goldenSundialDelete.executeUpdate();
            }
        } finally {
            goldenSundialConnection.close();
        }
    }

    public void deleteGoldenSundialAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_ACCOUNT_ID");
        goldenSundialAccountId = data;
        goldenSundialAuthorized = isAuthorized(data);
        applyGoldenSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
