import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianRaven {

    public void deleteObsidianRavenAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianRavenSink()).applyObsidianRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianRavenSink {
    public void applyObsidianRavenDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        try {
            PreparedStatement obsidianRavenDelete = obsidianRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianRavenDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianRavenDelete.executeUpdate();
            }
        } finally {
            obsidianRavenConnection.close();
        }
    }
}
