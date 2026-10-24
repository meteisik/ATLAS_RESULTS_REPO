import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianOrbit {

    private String obsidianOrbitAccountId;

    private boolean obsidianOrbitAuthorized;

    private void applyObsidianOrbitDeletion() throws SQLException {
        String data = obsidianOrbitAccountId;
        boolean authorized = obsidianOrbitAuthorized;
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        try {
            PreparedStatement obsidianOrbitDelete = obsidianOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianOrbitDelete.setString(1, data);
            obsidianOrbitDelete.executeUpdate();
        } finally {
            obsidianOrbitConnection.close();
        }
    }

    public void deleteObsidianOrbitAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("OBSIDIAN_ORBIT_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        obsidianOrbitAccountId = data;
        obsidianOrbitAuthorized = isAuthorized(data);
        applyObsidianOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
