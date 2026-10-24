import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_LunarCometSafe {

    private boolean checkLunarCometAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteLunarCometAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_COMET_ACCOUNT_ID");
        boolean authorized = checkLunarCometAccess(data);
        Connection lunarCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarComet");
        try {
            PreparedStatement lunarCometDelete = lunarCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarCometDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
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
