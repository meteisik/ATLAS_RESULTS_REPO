import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenSundialSafe {

    private void applyGoldenSundialDeletion(String data, boolean authorized) throws SQLException {
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
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyGoldenSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
