import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_LunarNebula {

    private boolean checkLunarNebulaAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteLunarNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_NEBULA_ACCOUNT_ID");
        boolean authorized = checkLunarNebulaAccess(data);
        Connection lunarNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarNebula");
        try {
            PreparedStatement lunarNebulaDelete = lunarNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarNebulaDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                lunarNebulaDelete.executeUpdate();
            }
        } finally {
            lunarNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
