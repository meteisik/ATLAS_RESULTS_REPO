import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_LunarHelixSafe {

    private boolean checkLunarHelixAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteLunarHelixAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_HELIX_ACCOUNT_ID");
        boolean authorized = checkLunarHelixAccess(data);
        Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
        try {
            PreparedStatement lunarHelixDelete = lunarHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                lunarHelixDelete.executeUpdate();
            }
        } finally {
            lunarHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
