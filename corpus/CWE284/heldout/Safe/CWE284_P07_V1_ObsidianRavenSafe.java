import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianRavenSafe {

    public void deleteObsidianRavenAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianRavenSafeChecker()).isAuthorized(data);
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        try {
            PreparedStatement obsidianRavenDelete = obsidianRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianRavenDelete.setString(1, data);
            if (authorized) {
                obsidianRavenDelete.executeUpdate();
            }
        } finally {
            obsidianRavenConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianRavenSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
