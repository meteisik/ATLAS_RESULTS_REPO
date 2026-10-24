import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_LunarNebula {

    public void deleteLunarNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_NEBULA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_LunarNebulaSink()).applyLunarNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_LunarNebulaSink {
    public void applyLunarNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection lunarNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarNebula");
        try {
            PreparedStatement lunarNebulaDelete = lunarNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarNebulaDelete.setString(1, data);
            lunarNebulaDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            lunarNebulaConnection.close();
        }
    }
}
