import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_LunarCometSafe {

    private String lunarCometAccountId;

    private boolean lunarCometAuthorized;

    private void applyLunarCometDeletion() throws SQLException {
        String data = lunarCometAccountId;
        boolean authorized = lunarCometAuthorized;
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

    public void deleteLunarCometAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_COMET_ACCOUNT_ID");
        lunarCometAccountId = data;
        lunarCometAuthorized = isAuthorized(data);
        applyLunarCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
