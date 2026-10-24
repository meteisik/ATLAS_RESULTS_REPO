import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianOrbit {

    public void deleteObsidianOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianOrbitSink()).applyObsidianOrbitDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianOrbitSink {
    public void applyObsidianOrbitDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        try {
            PreparedStatement obsidianOrbitDelete = obsidianOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianOrbitDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianOrbitDelete.executeUpdate();
            }
        } finally {
            obsidianOrbitConnection.close();
        }
    }
}
