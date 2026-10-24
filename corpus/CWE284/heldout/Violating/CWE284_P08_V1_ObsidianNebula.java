import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianNebula {

    public void deleteObsidianNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianNebulaSink()).applyObsidianNebulaDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianNebulaSink {
    public void applyObsidianNebulaDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        try {
            PreparedStatement obsidianNebulaDelete = obsidianNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianNebulaDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianNebulaDelete.executeUpdate();
            }
        } finally {
            obsidianNebulaConnection.close();
        }
    }
}
