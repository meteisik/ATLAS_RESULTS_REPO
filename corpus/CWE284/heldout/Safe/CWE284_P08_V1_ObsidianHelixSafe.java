import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianHelixSafe {

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianHelixSafeSink()).applyObsidianHelixDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianHelixSafeSink {
    public void applyObsidianHelixDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        try {
            PreparedStatement obsidianHelixDelete = obsidianHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianHelixDelete.executeUpdate();
            }
        } finally {
            obsidianHelixConnection.close();
        }
    }
}
