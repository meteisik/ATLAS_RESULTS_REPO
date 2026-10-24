import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_LunarNebulaSafe {

    private void applyLunarNebulaDeletion(String data, boolean authorized) throws SQLException {
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
        switch (7) {
        case 7:
            data = System.getenv("LUNAR_NEBULA_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyLunarNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
