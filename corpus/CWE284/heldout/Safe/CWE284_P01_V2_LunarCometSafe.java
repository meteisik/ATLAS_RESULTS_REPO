import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_LunarCometSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteLunarCometAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("LUNAR_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection lunarCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarComet");
        try {
            PreparedStatement lunarCometDelete = lunarCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarCometDelete.setString(1, data);
            if (authorized) {
                lunarCometDelete.executeUpdate();
            }
        } finally {
            lunarCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
