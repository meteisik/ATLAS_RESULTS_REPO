import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianComet {

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianCometSink()).applyObsidianCometDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianCometSink {
    public void applyObsidianCometDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianCometDelete.executeUpdate();
            }
        } finally {
            obsidianCometConnection.close();
        }
    }
}
