import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_ObsidianRaven {

    public void deleteObsidianRavenAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("OBSIDIAN_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_ObsidianRavenSink()).applyObsidianRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_ObsidianRavenSink {
    public void applyObsidianRavenDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        try {
            PreparedStatement obsidianRavenDelete = obsidianRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianRavenDelete.setString(1, data);
            obsidianRavenDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianRavenConnection.close();
        }
    }
}
