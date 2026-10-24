import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_LunarNebulaSafe {

    private String lunarNebulaAccountId;

    private boolean lunarNebulaAuthorized;

    private void applyLunarNebulaDeletion() throws SQLException {
        String data = lunarNebulaAccountId;
        boolean authorized = lunarNebulaAuthorized;
        Connection lunarNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarNebula");
        try {
            PreparedStatement lunarNebulaDelete = lunarNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarNebulaDelete.setString(1, data);
            if (authorized) {
                lunarNebulaDelete.executeUpdate();
            }
        } finally {
            lunarNebulaConnection.close();
        }
    }

    public void deleteLunarNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_NEBULA_ACCOUNT_ID");
        lunarNebulaAccountId = data;
        lunarNebulaAuthorized = isAuthorized(data);
        applyLunarNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
