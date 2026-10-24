import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_LunarHelixSafe {

    private String lunarHelixAccountId;

    private boolean lunarHelixAuthorized;

    private void applyLunarHelixDeletion() throws SQLException {
        String data = lunarHelixAccountId;
        boolean authorized = lunarHelixAuthorized;
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
        data = System.getenv("LUNAR_HELIX_ACCOUNT_ID");
        lunarHelixAccountId = data;
        lunarHelixAuthorized = isAuthorized(data);
        applyLunarHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
