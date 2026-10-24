import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_LunarComet {

    public void deleteLunarCometAccount() throws SQLException {
        String data;
        data = System.getenv("LUNAR_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_LunarCometSink()).applyLunarCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_LunarCometSink {
    public void applyLunarCometDeletion(String data, boolean authorized) throws SQLException {
        Connection lunarCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarComet");
        try {
            PreparedStatement lunarCometDelete = lunarCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            lunarCometDelete.setString(1, data);
            lunarCometDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            lunarCometConnection.close();
        }
    }
}
