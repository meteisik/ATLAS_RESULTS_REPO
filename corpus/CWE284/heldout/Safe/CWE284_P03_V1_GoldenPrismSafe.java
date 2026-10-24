import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenPrismSafe {

    private void applyGoldenPrismDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenPrism");
        try {
            PreparedStatement goldenPrismDelete = goldenPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenPrismDelete.setString(1, data);
            if (authorized) {
                goldenPrismDelete.executeUpdate();
            }
        } finally {
            goldenPrismConnection.close();
        }
    }

    public void deleteGoldenPrismAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_PRISM_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyGoldenPrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
