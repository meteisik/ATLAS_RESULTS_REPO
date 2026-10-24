import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianNebulaSafe {

    public void deleteObsidianNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianNebulaSafeSink()).applyObsidianNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianNebulaSafeSink {
    public void applyObsidianNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        try {
            PreparedStatement obsidianNebulaDelete = obsidianNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianNebulaDelete.setString(1, data);
            if (authorized) {
                obsidianNebulaDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianNebulaConnection.close();
        }
    }
}
