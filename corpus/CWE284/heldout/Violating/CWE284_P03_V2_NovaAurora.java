import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_NovaAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void applyNovaAuroraDeletion(String data, boolean authorized) throws SQLException {
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        try {
            PreparedStatement novaAuroraDelete = novaAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaAuroraDelete.setString(1, data);
            if (authorized) {
                novaAuroraDelete.executeUpdate();
            }
        } finally {
            novaAuroraConnection.close();
        }
    }

    public void deleteNovaAuroraAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("NOVA_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyNovaAuroraDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
