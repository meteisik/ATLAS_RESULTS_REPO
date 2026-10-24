import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianOrbit {

    public void deleteObsidianOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianOrbitSink()).applyObsidianOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianOrbitSink {
    public void applyObsidianOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        try {
            PreparedStatement obsidianOrbitDelete = obsidianOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianOrbitDelete.setString(1, data);
            obsidianOrbitDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianOrbitConnection.close();
        }
    }
}
