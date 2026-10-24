import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_LunarHelix {

    public void deleteLunarHelixAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_LunarHelixSink()).applyLunarHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_LunarHelixSink {
    public void applyLunarHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
        try {
            PreparedStatement lunarHelixDelete = lunarHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarHelixDelete.setString(1, data);
            lunarHelixDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            lunarHelixConnection.close();
        }
    }
}
