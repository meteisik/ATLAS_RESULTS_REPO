import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_SolarQuartz {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSolarQuartzAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("SOLAR_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_SolarQuartzSink()).applySolarQuartzDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_SolarQuartzSink {
    public void applySolarQuartzDeletion(CWE284_P09_V2_SolarQuartz.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        try {
            PreparedStatement solarQuartzDelete = solarQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarQuartzDelete.setString(1, data);
            solarQuartzDelete.executeUpdate();
        } finally {
            solarQuartzConnection.close();
        }
    }
}
