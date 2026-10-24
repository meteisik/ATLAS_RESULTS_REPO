import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticLantern {

    public void deleteArcticLanternAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_LANTERN_ACCOUNT_ID");
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticLanternSink()).applyArcticLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticLanternSink {
    public void applyArcticLanternDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        try {
            PreparedStatement arcticLanternDelete = arcticLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLanternDelete.setString(1, data);
            if (authorized) {
                arcticLanternDelete.executeUpdate();
            }
        } finally {
            arcticLanternConnection.close();
        }
    }
}
