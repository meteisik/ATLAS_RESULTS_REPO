import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneNebulaSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_NEBULA_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneNebulaSafeSink()).applyRuneNebulaDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneNebulaSafeSink {
    public void applyRuneNebulaDeletion(CWE284_P09_V1_RuneNebulaSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        try {
            PreparedStatement runeNebulaDelete = runeNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeNebulaDelete.setString(1, data);
            if (authorized) {
                runeNebulaDelete.executeUpdate();
            }
        } finally {
            runeNebulaConnection.close();
        }
    }
}
