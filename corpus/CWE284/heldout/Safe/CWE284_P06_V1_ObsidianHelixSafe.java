import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianHelixSafe {

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianHelixSafeSink()).applyObsidianHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianHelixSafeSink {
    public void applyObsidianHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        try {
            PreparedStatement obsidianHelixDelete = obsidianHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHelixDelete.setString(1, data);
            if (authorized) {
                obsidianHelixDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianHelixConnection.close();
        }
    }
}
