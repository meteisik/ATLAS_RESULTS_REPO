import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticRaven {
    private static boolean privateTrue = true;

    public void deleteArcticRavenAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ARCTIC_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticRavenSink()).applyArcticRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticRavenSink {
    public void applyArcticRavenDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
        try {
            PreparedStatement arcticRavenDelete = arcticRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticRavenDelete.setString(1, data);
            if (authorized) {
                arcticRavenDelete.executeUpdate();
            }
        } finally {
            arcticRavenConnection.close();
        }
    }
}
