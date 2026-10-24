import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenAurora {

    private void applyGoldenAuroraDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
        try {
            PreparedStatement goldenAuroraDelete = goldenAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenAuroraDelete.setString(1, data);
            if (authorized) {
                goldenAuroraDelete.executeUpdate();
            }
        } finally {
            goldenAuroraConnection.close();
        }
    }

    public void deleteGoldenAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_AURORA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyGoldenAuroraDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
