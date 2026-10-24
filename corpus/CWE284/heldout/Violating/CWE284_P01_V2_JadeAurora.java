import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteJadeAuroraAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("JADE_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        try {
            PreparedStatement jadeAuroraDelete = jadeAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeAuroraDelete.setString(1, data);
            jadeAuroraDelete.executeUpdate();
        } finally {
            jadeAuroraConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
