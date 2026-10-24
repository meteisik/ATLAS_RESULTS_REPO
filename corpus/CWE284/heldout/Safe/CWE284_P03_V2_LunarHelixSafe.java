import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_LunarHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void applyLunarHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
        try {
            PreparedStatement lunarHelixDelete = lunarHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarHelixDelete.setString(1, data);
            if (authorized) {
                lunarHelixDelete.executeUpdate();
            }
        } finally {
            lunarHelixConnection.close();
        }
    }

    public void deleteLunarHelixAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("LUNAR_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyLunarHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
