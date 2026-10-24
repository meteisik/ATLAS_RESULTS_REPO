import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteGoldenAuroraAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
