import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianRavenSafe {

    private String obsidianRavenAccountId;

    private boolean obsidianRavenAuthorized;

    private void applyObsidianRavenDeletion() throws SQLException {
        String data = obsidianRavenAccountId;
        boolean authorized = obsidianRavenAuthorized;
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

    public void deleteObsidianRavenAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("OBSIDIAN_RAVEN_ACCOUNT_ID");
            break;
        }
        obsidianRavenAccountId = data;
        obsidianRavenAuthorized = isAuthorized(data);
        applyObsidianRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
